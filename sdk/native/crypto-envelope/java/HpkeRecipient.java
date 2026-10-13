package org.zrotext.candidate;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.Arrays;
import javax.crypto.*;
import javax.crypto.spec.*;

/** Candidate-only RFC9180 base-mode, sequence-zero CEK unwrap; no manifest authority. */
public final class HpkeRecipient {
    private HpkeRecipient() {}
    /** Trusted application key adapter. This interface alone makes no custody claim. */
    public interface Recipient {
        byte[] unwrap(byte[] publicPoint,byte[] enc,byte[] info,byte[] aad,byte[] ciphertext)throws GeneralSecurityException;
    }
    static Recipient software(PrivateKey key){return (pk,enc,info,aad,ct)->open(key,pk,enc,info,aad,ct);}
    private static final byte[] EMPTY = new byte[0];
    private static final byte[] KEM = new byte[] {75,69,77,0,16};
    private static final byte[] SUITE = new byte[] {72,80,75,69,0,16,0,1,0,1};
    private static final byte[] VERSION = ascii("HPKE-v1");
    private static byte[] ascii(String value) { return value.getBytes(StandardCharsets.US_ASCII); }
    private static byte[] join(byte[]... pieces) {
        int size = 0; for (byte[] piece : pieces) size += piece.length;
        byte[] result = new byte[size]; int at = 0;
        for (byte[] piece : pieces) { System.arraycopy(piece, 0, result, at, piece.length); at += piece.length; }
        return result;
    }
    private static byte[] mac(byte[] key, byte[] input) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key.length == 0 ? new byte[32] : key, "HmacSHA256"));
        return mac.doFinal(input);
    }
    private static byte[] extract(byte[] suite, byte[] salt, String label, byte[] input) throws GeneralSecurityException {
        return mac(salt, join(VERSION, suite, ascii(label), input));
    }
    private static byte[] expand(byte[] suite, byte[] key, String label, byte[] info, int size) throws GeneralSecurityException {
        // All fixed outputs are <= SHA256's 32 bytes: exactly one HKDF block.
        byte[] block = mac(key, join(new byte[] {0, (byte)size}, VERSION, suite, ascii(label), info, new byte[] {1}));
        try { return Arrays.copyOf(block, size); } finally { Arrays.fill(block, (byte)0); }
    }
    static PublicKey point(byte[] value) throws GeneralSecurityException {
        if (value.length != 65 || value[0] != 4) throw new InvalidKeyException("P256 point encoding");
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec curve = parameters.getParameterSpec(ECParameterSpec.class);
        BigInteger x = new BigInteger(1, Arrays.copyOfRange(value, 1, 33));
        BigInteger y = new BigInteger(1, Arrays.copyOfRange(value, 33, 65));
        BigInteger p = ((ECFieldFp)curve.getCurve().getField()).getP();
        if (x.compareTo(p) >= 0 || y.compareTo(p) >= 0 || !y.multiply(y).mod(p).equals(
                x.multiply(x).multiply(x).add(curve.getCurve().getA().multiply(x)).add(curve.getCurve().getB()).mod(p)))
            throw new InvalidKeyException("P256 point not on curve");
        return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new ECPoint(x, y), curve));
    }
    /** Caller supplies an already authorized key handle; exportability is not attested here. */
    public static byte[] open(PrivateKey recipient, byte[] publicPoint, byte[] encapsulated,
                              byte[] info, byte[] aad, byte[] ciphertext) throws GeneralSecurityException {
        if (info.length > 36864 || aad.length > 36864 || ciphertext.length != 48)
            throw new GeneralSecurityException("Candidate wrap bounds");
        byte[] pk = publicPoint.clone(), enc = encapsulated.clone(), contextInfo = info.clone();
        byte[] authenticated = aad.clone(), encrypted = ciphertext.clone();
        PublicKey recipientPublic = point(pk); PublicKey ephemeral = point(enc);
        // JCA PrivateKey has no public-only derivation API. Prove that this native
        // handle matches pk without exporting its scalar. ECDH-only providers
        // that cannot sign must refuse this component until separately adapted.
        Signature binding = Signature.getInstance("SHA256withECDSA");
        byte[] challenge = join(ascii("ZTSE/recipient-key-binding/v1\0"), pk);
        binding.initSign(recipient); binding.update(challenge);
        byte[] proof = binding.sign();
        binding.initVerify(recipientPublic); binding.update(challenge);
        if (!binding.verify(proof)) throw new InvalidKeyException("Recipient key binding");
        KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
        agreement.init(recipient); agreement.doPhase(ephemeral, true);
        byte[] shared=agreement.generateSecret();
        try{return openAgreement(shared,pk,enc,contextInfo,authenticated,encrypted);}
        finally{Arrays.fill(shared,(byte)0);}
    }
    // Native adapters must independently prove public binding before supplying DH.
    static byte[] openAgreement(byte[] shared,byte[] pk,byte[] enc,byte[] contextInfo,byte[] authenticated,byte[] encrypted)throws GeneralSecurityException{
        if(shared.length!=32 || contextInfo.length>36864 || authenticated.length>36864 || encrypted.length!=48)
            throw new GeneralSecurityException("Candidate agreement bounds");
        point(pk);point(enc);
        byte[][] secrets = new byte[6][];
        try {
            secrets[0] = shared.clone();
            if (secrets[0].length != 32) throw new InvalidKeyException("P256 shared secret width");
            secrets[1] = extract(KEM, EMPTY, "eae_prk", secrets[0]);
            secrets[2] = expand(KEM, secrets[1], "shared_secret", join(enc, pk), 32);
            byte[] context = join(new byte[] {0}, extract(SUITE, EMPTY, "psk_id_hash", EMPTY), extract(SUITE, EMPTY, "info_hash", contextInfo));
            secrets[3] = extract(SUITE, secrets[2], "secret", EMPTY);
            secrets[4] = expand(SUITE, secrets[3], "key", context, 16);
            secrets[5] = expand(SUITE, secrets[3], "base_nonce", context, 12);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(secrets[4], "AES"), new GCMParameterSpec(128, secrets[5]));
            cipher.updateAAD(authenticated);
            return cipher.doFinal(encrypted);
        } finally {
            for (byte[] material : secrets) if (material != null) Arrays.fill(material, (byte)0);
        }
    }
}
