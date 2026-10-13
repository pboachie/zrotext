package org.zrotext.candidate;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import java.util.*;

/** Scalar import belongs only in this synthetic interoperability adapter. */
public final class HpkeTest {
    private HpkeTest() {}
    private interface Action { void run() throws GeneralSecurityException; }
    private static int checks;
    private static void rejects(Action action) throws GeneralSecurityException {
        try { action.run(); } catch (GeneralSecurityException | IllegalArgumentException expected) { checks++; return; }
        throw new AssertionError("Invalid wrap accepted");
    }
    private static byte[] mutate(byte[] value) {
        if (value.length == 0) return new byte[] {1};
        var changed = value.clone(); changed[changed.length - 1] ^= 1; return changed;
    }
    public static void main(String[] ignored) throws Exception {
        var reader = new BufferedReader(new InputStreamReader(System.in, java.nio.charset.StandardCharsets.UTF_8));
        int vectors = 0;
        for (String line; (line = reader.readLine()) != null;) {
            var fields = line.split("\t", -1);
            if (fields.length != 9) throw new AssertionError("Fixture fields");
            byte[][] data = new byte[7][];
            for (int i=0; i<7; i++) data[i] = HexFormat.of().parseHex(fields[i+2]);
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec("secp256r1"));
            var curve = parameters.getParameterSpec(ECParameterSpec.class);
            var key = KeyFactory.getInstance("EC").generatePrivate(new ECPrivateKeySpec(new BigInteger(1,data[0]),curve));
            var plaintext = HpkeRecipient.open(key,data[1],data[2],data[3],data[4],data[5]);
            if (!Arrays.equals(plaintext,data[6])) throw new AssertionError("Cross-client plaintext mismatch");
            Arrays.fill(plaintext,(byte)0); checks++; vectors++;
            byte[] negated = data[1].clone();
            BigInteger prime = ((ECFieldFp)curve.getCurve().getField()).getP();
            byte[] opposite = prime.subtract(new BigInteger(1,Arrays.copyOfRange(negated,33,65))).toByteArray();
            Arrays.fill(negated,33,65,(byte)0);
            System.arraycopy(opposite,Math.max(0,opposite.length-32),negated,65-Math.min(32,opposite.length),Math.min(32,opposite.length));
            try { HpkeRecipient.open(key,negated,data[2],data[3],data[4],new byte[48]); throw new AssertionError("Unbound recipient"); }
            catch (InvalidKeyException expected) {
                if (!"Recipient key binding".equals(expected.getMessage())) throw expected;
                checks++;
            }
            for (int i=1;i<=5;i++) {
                final int index=i;
                var changed = data.clone(); changed[index] = mutate(changed[index]);
                rejects(() -> HpkeRecipient.open(key,changed[1],changed[2],changed[3],changed[4],changed[5]));
            }
            rejects(() -> HpkeRecipient.open(key,data[1],new byte[65],data[3],data[4],data[5]));
            byte[] offCurve = new byte[65]; offCurve[0]=4;
            rejects(() -> HpkeRecipient.open(key,data[1],offCurve,data[3],data[4],data[5]));
            rejects(() -> HpkeRecipient.open(key,data[1],new byte[33],data[3],data[4],data[5]));
            rejects(() -> HpkeRecipient.open(key,data[1],data[2],new byte[36865],data[4],data[5]));
            rejects(() -> HpkeRecipient.open(key,data[1],data[2],data[3],new byte[36865],data[5]));
            rejects(() -> HpkeRecipient.open(key,data[1],data[2],data[3],data[4],new byte[47]));
        }
        if (vectors < 2) throw new AssertionError("Missing profile component vectors");
        System.out.println("Java HPKE: " + checks + " checks on " + vectors + " vectors passed");
    }
}
