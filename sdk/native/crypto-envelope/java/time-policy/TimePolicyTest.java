package org.zrotext.candidate;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.GeneralSecurityException;
import java.util.*;

public final class TimePolicyTest {
    private TimePolicyTest(){}
    static String open(Map<String,byte[]> wire,Election03.Proof proof,Map<String,Object> authority,long now,byte[] envelope)throws Exception{
        var parameters=java.security.AlgorithmParameters.getInstance("EC");parameters.init(new java.security.spec.ECGenParameterSpec("secp256r1"));
        var reader=java.security.KeyFactory.getInstance("EC").generatePrivate(new java.security.spec.ECPrivateKeySpec(new java.math.BigInteger(1,wire.get("readerScalar")),parameters.getParameterSpec(java.security.spec.ECParameterSpec.class)));
        return ElectedReader03.openSoftware(envelope,proof.acceptedManifest(),proof,()->new ElectedReader03.AuthoritySnapshot(authority,now),wire.get("message"),"+12",reader);
    }
    public static void main(String[] args)throws Exception{
        if(args.length==1 && args[0].equals("--probe")){try{ProtectedSigner.probe();}catch(GeneralSecurityException e){System.exit(77);}return;}
        if(args.length!=1)throw new IllegalArgumentException("External pending receipt required");
        boolean readerMode=args[0].equals("--readers");Path receipt=Path.of(args[0]);ProtectedSigner owner=null;
        try{
            if(!readerMode){
            owner=ProtectedSigner.create(alias->{try(var stream=FileChannel.open(receipt,StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE,StandardOpenOption.SYNC)){var b=StandardCharsets.UTF_8.encode(alias+"\n");while(b.hasRemaining())stream.write(b);stream.force(true);}});
            System.out.println(HexFormat.of().formatHex(owner.publicPoint()));System.out.flush();
            }
            final var signer=owner;
            String input=new String(System.in.readAllBytes(),StandardCharsets.UTF_8);int count=0;
            for(String block:input.replace("\r\n","\n").strip().split("\n\n")){
                var lines=block.lines().toList();var head=lines.get(0).split("\t");
                if(head.length!=5)throw new AssertionError("Policy header");
                String name=head[0];boolean accept=head[1].equals("true");long observed=Long.parseLong(head[2]),now=Long.parseLong(head[3]),expires=Long.parseLong(head[4]);
                Map<String,byte[]> wire=new HashMap<>();Map<String,Object> accepted=new HashMap<>(),authority=new HashMap<>();
                for(String line:lines.subList(1,lines.size())){String[] f=line.split("\t");Object value=f[1].equals("b")?HexFormat.of().parseHex(f[2]):Long.valueOf(f[2]);if(f[0].startsWith("accepted."))accepted.put(f[0].substring(9),value);else if(f[0].startsWith("authority."))authority.put(f[0].substring(10),value);else wire.put(f[0],(byte[])value);}
                // Evidence verification is outside the expected composition-refusal catch.
                var prior=ManifestChain.genesis02(wire.get("signed02"),ManifestChain.RootPin.enroll(wire.get("rootPin"),wire.get("fingerprint")),10000);
                var proof=Election03.verify(wire.get("bundle"),wire.get("core"),accepted,prior,wire.get("signed02"),wire.get("signed03"),wire.get("deviceSigningPoint"),wire.get("ownerApprovalPoint"));
                var recipients=new ArrayList<Compose03.Recipient>();for(var key:proof.acceptedManifest().keyRecords())if(key[0]>=1 && key[0]<=3)recipients.add(new Compose03.Recipient(key[0],Arrays.copyOfRange(key,1,33)));
                if(readerMode){
                    SignedEnvelope.verify(wire.get("envelope"),3,wire.get("signerPoint"));
                    String opened;
                    try{opened=open(wire,proof,authority,now,wire.get("envelope"));}catch(GeneralSecurityException|IllegalArgumentException e){if(accept)throw new AssertionError("Accepted reader policy refused: "+name,e);System.out.println("READ "+name+" refused");count++;continue;}
                    if(!accept || !opened.equals(new String(wire.get("bodyText"),StandardCharsets.UTF_8)))throw new AssertionError("Reader policy mismatch: "+name);
                    System.out.println("READ "+name+" accepted");count++;continue;
                }
                var request=new Compose03.Request(proof.acceptedManifest(),proof,()->new ElectedReader03.AuthoritySnapshot(authority,now),wire.get("message"),observed,expires,"+12",new String(wire.get("bodyText"),StandardCharsets.UTF_8),signer,recipients);
                byte[] envelope;
                try{envelope=Compose03.fresh(request);}catch(GeneralSecurityException|IllegalArgumentException e){if(accept)throw new AssertionError("Accepted policy refused: "+name,e);System.out.println("REFUSED "+name);count++;continue;}
                if(!accept)throw new AssertionError("Policy rejection missing: "+name);
                if(!open(wire,proof,authority,now,envelope).equals(request.content()))throw new AssertionError("Native policy self-open: "+name);
                System.out.println("ENVELOPE "+name+" "+Base64.getEncoder().encodeToString(envelope));count++;
            }
            System.out.println((readerMode?"READERS: ":"QUALIFIED: ")+count+" Java signed time-policy cases passed");
        }finally{if(owner!=null){owner.deleteCreated();Files.delete(receipt);owner.close();}}
    }
}
