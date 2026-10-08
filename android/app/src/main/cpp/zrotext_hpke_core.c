// SPDX-License-Identifier: AGPL-3.0-only
/* ZROtext AndroidKeyStore HPKE receiver core.
 *
 * Per the #1003 GO-WITH-CONDITIONS review, section 3, the bridge contract is:
 *   1. one crypto-callback device registered once per process;
 *   2. a public-only recipient ecc_key per open, carrying the per-open
 *      recipient context in devCtx, initialized with that device id;
 *   3. the callback validates the curve id and the 32-byte secret width,
 *      re-encodes the peer key as 0x04 || X || Y for the host platform, and
 *      returns only hard errors, never CRYPTOCB_UNAVAILABLE;
 *   4. the wrapper enforces the profile-level input checks wolfSSL leaves to
 *      callers: enc is exactly 65 bytes, C is at least 17, ctSz excludes the
 *      16-byte inline AEAD tag, and info/AAD are nonempty and distinct.
 */
#include "zrotext_hpke_core.h"

#include <limits.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/cryptocb.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/hpke.h>
#include <wolfssl/wolfcrypt/memory.h>

/* The one registered crypto device of this process. The value is arbitrary
 * as long as it is not INVALID_DEVID and no other wolfSSL user of this
 * process registers the same id; the bridge is the only wolfSSL consumer in
 * this native library. */
#define ZT_HPKE_DEVID 0x5A544B31 /* "ZTK1" */

/* Binding condition 2 (maintainer, #1003): the bridge callback NEVER returns
 * CRYPTOCB_UNAVAILABLE. Every key operation is answered here or hard-fails,
 * because with WOLF_CRYPTO_CB_ONLY_ECC there is no software ECDH to fall
 * through to, and treating a broken bridge as "device unavailable" would
 * misreport a packaging or registration defect as a missing key. */
static int zt_ecdh_callback(int devId, wc_CryptoInfo* info, void* ctx)
{
    ecc_key* priv;
    ecc_key* peer;
    byte* out;
    word32* outLen;
    const struct zt_hpke_bridge* bridge;
    byte peerPoint[DHKEM_P256_ENC_LEN];
    word32 peerPointSz = (word32)sizeof(peerPoint);
    int rc;

    (void)devId;
    (void)ctx;

    if (info == NULL || info->algo_type != WC_ALGO_TYPE_PK)
        return BAD_STATE_E;
    /* The bridge answers exactly one algorithm. Anything else dispatched to
     * this device means the key object leaked into another code path; fail
     * closed instead of silently answering or falling through. */
    if (info->pk.type != WC_PK_TYPE_ECDH)
        return BAD_STATE_E;

    priv = info->pk.ecdh.private_key;
    peer = info->pk.ecdh.public_key;
    out = info->pk.ecdh.out;
    outLen = info->pk.ecdh.outlen;
    if (priv == NULL || peer == NULL || out == NULL || outLen == NULL)
        return BAD_FUNC_ARG;
    if (priv->dp == NULL || peer->dp == NULL)
        return ECC_BAD_ARG_E;
    /* Review contract step 4: reject a non-P-256 key pair before the host
     * platform ever sees it. */
    if (priv->dp->id != ECC_SECP256R1 || peer->dp->id != ECC_SECP256R1)
        return ECC_BAD_ARG_E;
    if (*outLen < 32U)
        return ECC_BAD_ARG_E;

    bridge = (const struct zt_hpke_bridge*)priv->devCtx;
    if (bridge == NULL || bridge->agree == NULL)
        return BAD_STATE_E;

    /* Re-encode the ephemeral peer key for the host: 65 bytes, 0x04 || X || Y.
     * The key was imported as a public-only P-256 key by this bridge, so the
     * encoding is fixed-width. */
    XMEMSET(peerPoint, 0, sizeof(peerPoint));
    if (wc_ecc_export_x963_ex(peer, peerPoint, &peerPointSz, 0) != 0 ||
        peerPointSz != DHKEM_P256_ENC_LEN) {
        wc_ForceZero(peerPoint, sizeof(peerPoint));
        return ECC_BAD_ARG_E;
    }

    rc = bridge->agree(bridge->ctx, peerPoint, out);
    wc_ForceZero(peerPoint, sizeof(peerPoint));
    if (rc != 0 || rc == CRYPTOCB_UNAVAILABLE) {
        /* A host implementation must not smuggle the unavailable code past
         * this guard; treat any non-zero answer as the hard failure it is. */
        return (rc == 0) ? BAD_STATE_E : rc;
    }

    /* wc_ecc_shared_secret's ANSI X9.63 output is the 32-byte big-endian X
     * coordinate for P-256 (ecc.h), which is exactly RFC 9180's DH(). */
    *outLen = 32U;
    return 0;
}

static int zt_device_registered = 0;

int zt_hpke_init(void)
{
    if (zt_device_registered == 0) {
        if (wc_CryptoCb_RegisterDevice(ZT_HPKE_DEVID, zt_ecdh_callback, NULL) != 0)
            return BAD_STATE_E;
        zt_device_registered = 1;
    }
    return 0;
}

void zt_hpke_deinit(void)
{
    wc_CryptoCb_UnRegisterDevice(ZT_HPKE_DEVID);
    zt_device_registered = 0;
}

int zt_hpke_open(const struct zt_hpke_bridge* bridge,
                 const unsigned char* recipient, size_t recipientSz,
                 const unsigned char* enc, size_t encSz,
                 const unsigned char* ct, size_t ctSz,
                 const unsigned char* info, size_t infoSz,
                 const unsigned char* aad, size_t aadSz,
                 unsigned char* pt, size_t ptCap)
{
    Hpke hpke;
    ecc_key recipientKey;
    int ret;

    if (bridge == NULL || recipient == NULL || enc == NULL || ct == NULL ||
        info == NULL || aad == NULL || pt == NULL)
        return BAD_FUNC_ARG;
    if (recipientSz > (size_t)INT_MAX || encSz > (size_t)INT_MAX ||
        ctSz > (size_t)INT_MAX || infoSz > (size_t)INT_MAX ||
        aadSz > (size_t)INT_MAX)
        return BAD_FUNC_ARG;

    /* Profile-level framing checks the wolfSSL API leaves to the caller
     * (review condition 3 and the hpke.h seal/tag framing warning). The wire
     * stores the tag contiguously after ctSz plaintext bytes; wolfSSL reads
     * the tag from ciphertext + ctSz, so ctSz passed down excludes the tag. */
    if (recipientSz != (size_t)DHKEM_P256_ENC_LEN)
        return BAD_FUNC_ARG;
    if (encSz != (size_t)DHKEM_P256_ENC_LEN)
        return BAD_FUNC_ARG;
    if (ctSz < 17U)
        return BAD_FUNC_ARG;
    if (infoSz == 0U || aadSz == 0U)
        return BAD_FUNC_ARG;
    if (infoSz == aadSz && XMEMCMP(info, aad, (word32)infoSz) == 0)
        return BAD_FUNC_ARG;
    if (ptCap < ctSz - 16U)
        return BUFFER_E;

    ret = zt_hpke_init();
    if (ret != 0)
        return ret;

    XMEMSET(&hpke, 0, sizeof(hpke));
    XMEMSET(&recipientKey, 0, sizeof(recipientKey));

    ret = wc_HpkeInit(&hpke, DHKEM_P256_HKDF_SHA256, HKDF_SHA256,
        HPKE_AES_128_GCM, NULL);
    if (ret != 0)
        return ret;

    /* Public-only recipient key per open (review contract step 2). It never
     * holds private material: the scalar lives behind the Keystore alias, and
     * a public-only key also makes any accidental non-callback software path
     * fail the private-key type gate. One key per open keeps the timing-
     * resistant decap path off shared state. The imported point is THIS
     * recipient's enrolled public key; the sender's ephemeral key (enc) is
     * passed to wc_HpkeOpenBase separately as the KEM peer. */
    ret = wc_ecc_init_ex(&recipientKey, NULL, ZT_HPKE_DEVID);
    if (ret != 0)
        return ret;
    recipientKey.devCtx = (void*)bridge;

    ret = wc_ecc_import_x963_ex(recipient, (word32)recipientSz,
        &recipientKey, ECC_SECP256R1);
    if (ret == 0) {
        ret = wc_HpkeOpenBase(&hpke, &recipientKey, enc, (word16)encSz,
            (byte*)info, (word32)infoSz, (byte*)aad, (word32)aadSz,
            (byte*)ct, (word32)(ctSz - 16U), pt);
    }

    wc_ecc_free(&recipientKey);
    wc_ForceZero(&hpke, sizeof(hpke));
    return ret;
}
