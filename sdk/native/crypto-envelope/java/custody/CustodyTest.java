package org.zrotext.candidate;
import java.nio.channels.FileChannel;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.util.*;

public final class CustodyTest {
    private CustodyTest(){}
    interface Attempt{void run()throws Exception;}
    static int checks;
    static void check(boolean value){if(!value)throw new AssertionError("Protected test");checks++;}
    static void refuses(Attempt work)throws Exception{try{work.run();}catch(GeneralSecurityException|IllegalArgumentException e){checks++;return;}throw new AssertionError("Missing refusal");}
    public static void main(String[] args)throws Exception{
        if(args.length==1 && args[0].equals("--probe")){try{ProtectedRecipient.probe();}catch(GeneralSecurityException e){System.exit(77);}return;}
        if(args.length!=1)throw new IllegalArgumentException("Pending receipt required");
        Path receipt=Path.of(args[0]);ProtectedRecipient owner=null;boolean deleted=false;
        try{
            owner=ProtectedRecipient.create(alias->{try(var file=FileChannel.open(receipt,StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE,StandardOpenOption.SYNC)){
                ByteBuffer data=StandardCharsets.UTF_8.encode(alias+"\n");while(data.hasRemaining())file.write(data);file.force(true);
            }});final var key=owner;byte[] point=key.publicPoint();check(point.length==65);System.out.println(HexFormat.of().formatHex(point));System.out.flush();
            try(var reopened=ProtectedRecipient.open(key.alias(),point)){check(MessageDigest.isEqual(reopened.publicPoint(),point));refuses(reopened::deleteCreated);}
            var generator=KeyPairGenerator.getInstance("EC");generator.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));var other=(java.security.interfaces.ECPublicKey)generator.generateKeyPair().getPublic();
            byte[] wrong=new byte[65];wrong[0]=4;byte[] x=other.getW().getAffineX().toByteArray(),y=other.getW().getAffineY().toByteArray();int nx=Math.min(32,x.length),ny=Math.min(32,y.length);System.arraycopy(x,x.length-nx,wrong,33-nx,nx);System.arraycopy(y,y.length-ny,wrong,65-ny,ny);
            refuses(()->{try(var unexpected=ProtectedRecipient.open(key.alias(),wrong)){unexpected.publicPoint();}});
            Map<String,byte[]> wire=new HashMap<>();Map<String,Object> accepted=new HashMap<>(),authority=new HashMap<>();
            Scanner input=new Scanner(System.in,StandardCharsets.UTF_8);while(input.hasNextLine()){
                String[] f=input.nextLine().split("\t");Object value=f[1].equals("b")?HexFormat.of().parseHex(f[2]):Long.valueOf(f[2]);
                if(f[0].startsWith("accepted."))accepted.put(f[0].substring(9),value);else if(f[0].startsWith("authority."))authority.put(f[0].substring(10),value);else wire.put(f[0],(byte[])value);
            }
            var manifest=ManifestChain.genesis02(wire.get("02.manifest"),ManifestChain.RootPin.enroll(wire.get("02.rootPin"),wire.get("02.fingerprint")),10000);
            SealedReader02.CurrentSelection current=(a,v,d,w)->Arrays.equals(a,manifest.account()) && v==manifest.version() && Arrays.equals(d,manifest.digest());
            for(String kind:new String[]{"inbound","outbound"})check(SealedReader02.openWithRecipient(wire.get("02."+kind),manifest,10000,2,wire.get("02.reader"),key,current).equals(new String(wire.get("02.text"),StandardCharsets.UTF_8)));
            refuses(()->SealedReader02.openWithRecipient(wire.get("02.inbound"),manifest,10000,2,wire.get("02.reader"),key,(a,v,d,w)->false));
            var prior=ManifestChain.genesis02(wire.get("03.signed02"),ManifestChain.RootPin.enroll(wire.get("03.rootPin"),wire.get("03.fingerprint")),10000);
            var proof=Election03.verify(wire.get("03.bundle"),wire.get("03.core"),accepted,prior,wire.get("03.signed02"),wire.get("03.signed03"),wire.get("03.deviceSigningPoint"),wire.get("03.ownerApprovalPoint"));
            ElectedReader03.AuthoritySource source=()->new ElectedReader03.AuthoritySnapshot(authority,30000);
            check(ElectedReader03.openWithRecipient(wire.get("03.envelope"),proof.acceptedManifest(),proof,source,wire.get("03.message"),"+12",key).equals(new String(wire.get("03.text"),StandardCharsets.UTF_8)));
            refuses(()->ElectedReader03.openWithRecipient(wire.get("03.envelope"),proof.acceptedManifest(),proof,source,wire.get("03.message"),"+13",key));
            String alias=key.alias();key.deleteCreated();deleted=true;refuses(key::publicPoint);
            refuses(()->ElectedReader03.openWithRecipient(wire.get("03.envelope"),proof.acceptedManifest(),proof,source,wire.get("03.message"),"+12",key));
            refuses(()->{try(var unexpected=ProtectedRecipient.open(alias,point)){unexpected.publicPoint();}});Files.delete(receipt);
            System.out.println("QUALIFIED: "+checks+" native Java PCP checks passed; owned key deleted");
        }finally{if(owner!=null){try{if(!deleted){owner.deleteCreated();Files.delete(receipt);}}finally{owner.close();}}}
    }
}
