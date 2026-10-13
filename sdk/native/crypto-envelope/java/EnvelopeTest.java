package org.zrotext.candidate;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.util.*;

public final class EnvelopeTest {
    private EnvelopeTest() {}
    private static int checks;
    private interface Attempt { void run() throws GeneralSecurityException; }
    private static void reject(Attempt attempt) throws GeneralSecurityException {
        try { attempt.run(); } catch(GeneralSecurityException expected) {checks++;return;}
        throw new AssertionError("Invalid envelope accepted");
    }
    public static void main(String[] ignored) throws Exception {
        var reader=new BufferedReader(new InputStreamReader(System.in,java.nio.charset.StandardCharsets.UTF_8));int rows=0;
        for(String line;(line=reader.readLine())!=null;) {
            var f=line.split("\t",-1);if(f.length!=9)throw new AssertionError("Fixture fields");
            int profile=Integer.parseInt(f[1]),role=Integer.parseInt(f[5]);var hex=HexFormat.of();
            byte[] bytes=hex.parseHex(f[2]), signer=hex.parseHex(f[3]),bodyAad=hex.parseHex(f[4]),id=hex.parseHex(f[6]);
            var signed=SignedEnvelope.verify(bytes,profile,signer);
            if(!Arrays.equals(signed.bodyAad(),bodyAad) || !Arrays.equals(signed.wrapInfo(role,id),hex.parseHex(f[7])) || !Arrays.equals(signed.wrapAad(role,id),hex.parseHex(f[8])))throw new AssertionError("Transcript mismatch");
            checks+=3;rows++;
            if(profile==3){
                byte[] zeroMessage=bytes.clone();Arrays.fill(zeroMessage,26,42,(byte)0);
                try {SignedEnvelope.verify(zeroMessage,profile,signer);throw new AssertionError("Zero message accepted");}
                catch(GeneralSecurityException expected){if(!"Profile03 message identity".equals(expected.getMessage()))throw expected;checks++;}
            }
            byte[] copied=signed.bytes();Arrays.fill(copied,(byte)0);
            if(!Arrays.equals(signed.bytes(),bytes))throw new AssertionError("Mutable snapshot");checks++;
            for(int at:new int[]{0,4,5,6,7,8,9,10,74,114,146,154,162,bytes.length-65,bytes.length-1}) {
                byte[] changed=bytes.clone();changed[at]^=1;reject(()->SignedEnvelope.verify(changed,profile,signer));
            }
            reject(()->SignedEnvelope.verify(bytes,profile==2?3:2,signer));
            reject(()->SignedEnvelope.verify(Arrays.copyOf(bytes,bytes.length-1),profile,signer));
            reject(()->SignedEnvelope.verify(Arrays.copyOf(bytes,bytes.length+1),profile,signer));
            reject(()->signed.wrapInfo(role,new byte[32]));
            byte[] high=bytes.clone();var order=new BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",16);
            byte[] scalar=order.subtract(new BigInteger(1,Arrays.copyOfRange(bytes,bytes.length-32,bytes.length))).toByteArray();
            Arrays.fill(high,high.length-32,high.length,(byte)0);System.arraycopy(scalar,Math.max(0,scalar.length-32),high,high.length-Math.min(32,scalar.length),Math.min(32,scalar.length));
            reject(()->SignedEnvelope.verify(high,profile,signer));
            Arrays.fill(bytes,(byte)0);if(!Arrays.equals(signed.bodyAad(),bodyAad))throw new AssertionError("Caller mutation changed verified bytes");checks++;
        }
        if(rows<3)throw new AssertionError("Missing fixture coverage");
        System.out.println("Java envelope: "+checks+" checks on "+rows+" rows passed");
    }
}
