// SPDX-License-Identifier: AGPL-3.0-only
#ifndef ZROTEXT_HPKE_CORE_H
#define ZROTEXT_HPKE_CORE_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ZROtext AndroidKeyStore HPKE receiver core.
 *
 * Opens one RFC 9180 base-mode DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 /
 * AES-128-GCM ciphertext where the recipient ECDH is answered by the host
 * platform (AndroidKeyStore via JNI, or a software test key in the host KAT).
 * wolfSSL is built with WOLF_CRYPTO_CB_ONLY_ECC (user_settings.h): software
 * ECDH does not exist in this binary, so every recipient ECDH is answered by
 * the registered crypto callback or fails closed with NO_VALID_DEVID.
 */

/* Fills the crypto-callback registry once per process. Idempotent. */
int zt_hpke_init(void);

/* Removes the registration; paired with zt_hpke_init for library unload. */
void zt_hpke_deinit(void);

/* One RFC 9180 open operation.
 *
 * bridge          answers the recipient ECDH (see zt_hpke_bridge).
 * recipient/recipientSz
 *                 THIS recipient's enrolled public point; exactly 65 bytes,
 *                 0x04 || X || Y. It becomes the public part of the device
 *                 key handle and the pkR side of the KEM context.
 * enc/encSz       the sender ephemeral public key; exactly 65 bytes,
 *                 0x04 || X || Y (DHKEM_P256_ENC_LEN).
 * ct/ctSz         ciphertext INCLUDING its trailing 16-byte AEAD tag, per the
 *                 ZROtext wire framing; ctSz must be at least 17.
 * info/infoSz     HPKE key-schedule info; must be nonempty.
 * aad/aadSz       HPKE AEAD associated data; must be nonempty and distinct
 *                 from info.
 * pt/ptCap        output buffer; capacity must be at least ctSz - 16.
 *
 * Returns 0 and writes ctSz - 16 plaintext bytes on success; a hard negative
 * wolfSSL error code otherwise. The DH shared secret produced inside the
 * callback is a per-message transient: wolfSSL zeroes its copy after the KEM
 * ExtractAndExpand, and the bridge zeroes its own copies after use.
 */
typedef struct zt_hpke_bridge {
    /* Given the peer's 65-byte uncompressed P-256 public point, compute the
     * 32-byte big-endian X coordinate of the ECDH shared secret into out.
     * Returns 0 on success or a hard negative error code. Must NEVER return
     * CRYPTOCB_UNAVAILABLE: that code would re-open software fallback paths
     * in non-only builds and masks a broken bridge as "no device". */
    int (*agree)(void* ctx, const unsigned char* peer_point, unsigned char* out);
    void* ctx;
} zt_hpke_bridge;

int zt_hpke_open(const struct zt_hpke_bridge* bridge,
                 const unsigned char* recipient, size_t recipientSz,
                 const unsigned char* enc, size_t encSz,
                 const unsigned char* ct, size_t ctSz,
                 const unsigned char* info, size_t infoSz,
                 const unsigned char* aad, size_t aadSz,
                 unsigned char* pt, size_t ptCap);

#ifdef __cplusplus
}
#endif

#endif /* ZROTEXT_HPKE_CORE_H */
