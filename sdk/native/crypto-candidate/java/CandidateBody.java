// SPDX-License-Identifier: AGPL-3.0-only
package org.zrotext.candidate;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Candidate symmetric primitive only: establishes no signer, routing or manifest authority. */
public final class CandidateBody {
    private CandidateBody() {}

    /** Caller must have verified all envelope authority and recovered the authorized content key. */
    public static String open(byte[] contentKey, byte[] nonce, byte[] verifiedAad, byte[] ciphertext) {
        if (contentKey == null || contentKey.length != 32 || nonce == null || nonce.length != 12
                || verifiedAad == null || verifiedAad.length == 0 || verifiedAad.length > 36864
                || ciphertext == null || ciphertext.length < 17 || ciphertext.length > 32784) {
            throw new BodyException("shape");
        }
        byte[] plaintext = null;
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(contentKey, "AES"), new GCMParameterSpec(128, nonce));
            cipher.updateAAD(verifiedAad);
            plaintext = cipher.doFinal(ciphertext);
            return decode(plaintext);
        } catch (GeneralSecurityException failure) {
            throw new BodyException("authentication");
        } finally {
            if (plaintext != null) Arrays.fill(plaintext, (byte) 0);
        }
    }

    public static String decode(byte[] bytes) {
        if (bytes == null || bytes.length < 1 || bytes.length > 32768) throw new BodyException("length");
        for (byte value : bytes) if (value == 0) throw new BodyException("nul");
        if (bytes.length >= 3 && bytes[0] == (byte) 0xef && bytes[1] == (byte) 0xbb && bytes[2] == (byte) 0xbf)
            throw new BodyException("bom");
        try {
            return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString();
        } catch (CharacterCodingException failure) { throw new BodyException("utf8"); }
    }

    public static final class BodyException extends IllegalArgumentException {
        private static final long serialVersionUID = 1L;
        public final String reason;
        private BodyException(String reason) { super("candidate body: " + reason); this.reason = reason; }
    }
}
