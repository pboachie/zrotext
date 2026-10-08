// SPDX-License-Identifier: AGPL-3.0-only
/* Host-runnable known-answer tests for the ZROtext HPKE receiver bridge.
 *
 * LABEL: this is the SOFTWARE-KEY variant of the bridge KAT required by the
 * #1003 provider selection. It exercises the exact production wolfSSL subset
 * (cryptocb-only ECC build), the exact production wrapper (zrotext_hpke_core)
 * and the exact callback contract, with the Keystore role played by a software
 * test key from RFC 9180. It is an ADDITIONAL test lane: it does not replace
 * the AndroidKeyStore instrumentation KATs, which run on an API 31+ emulator
 * in the android-device-smoke workflow. A run of only this suite is NOT
 * provider acceptance.
 *
 * The recipient private key below is the published RFC 9180 A.3 test scalar
 * (public test material, not ZROtext key material). The point arithmetic for
 * the software key uses wolfSSL's own SP integer implementation, the same
 * math the library links; it does not touch the wc_ecc high-level path, which
 * this build compiles without software ECDH.
 */
#include <stdio.h>
#include <string.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/cryptocb.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/hpke.h>
#include <wolfssl/wolfcrypt/sp_int.h>
#include <wolfssl/wolfcrypt/wc_port.h>

#include "zrotext_hpke_core.h"

/* RFC 9180 A.3.1 base mode, DHKEM(P-256, HKDF-SHA256)/HKDF-SHA256/AES-128-GCM,
 * first encryption: public test vector values. */
#define SK_R_HEX "f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2"
#define ENC_HEX \
    "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac9" \
    "8536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4"
#define CT_HEX \
    "5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f" \
    "9076ac232e3ab2523f39513434"
#define PK_R_HEX \
    "04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a8" \
    "26a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0"
#define SHARED_SECRET_HEX \
    "13f918529458d2542531406888c8a6d4ea7ff473a6f4db452ac3c4ae1d01cea1"
static const char INFO_TEXT[] = "Ode on a Grecian Urn";
static const char AAD_TEXT[] = "Count-0";
static const char PLAINTEXT_TEXT[] = "Beauty is truth, truth beauty";

/* NIST P-256 domain: p and a = -3 mod p. */
#define P_HEX \
    "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"
#define A_HEX \
    "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc"

static const size_t ENC_LEN = 65;
static const size_t CT_LEN = 45;
static const size_t PT_LEN = 29;

static size_t hexNibble(char c)
{
    if (c >= '0' && c <= '9') return (size_t)(c - '0');
    if (c >= 'a' && c <= 'f') return (size_t)(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return (size_t)(c - 'A' + 10);
    return 0xFF;
}

static size_t hexDecode(const char* hex, unsigned char* out, size_t outCap)
{
    size_t count = 0;
    while (hex[0] != '\0' && hex[1] != '\0') {
        size_t hi = hexNibble(hex[0]);
        size_t lo = hexNibble(hex[1]);
        if (hi == 0xFF || lo == 0xFF || count >= outCap)
            return 0;
        out[count++] = (unsigned char)((hi << 4) | lo);
        hex += 2;
    }
    if (hex[0] != '\0')
        return 0;
    return count;
}

/* --- software P-256 scalar multiplication over wolfSSL's SP integers ---- */

static sp_int zt_p, zt_a; /* curve constants, set up once */

static int fieldSetup(void)
{
    return sp_init(&zt_p) == 0 && sp_init(&zt_a) == 0 &&
        sp_read_radix(&zt_p, P_HEX, 16) == 0 &&
        sp_read_radix(&zt_a, A_HEX, 16) == 0 ? 0 : -1;
}

typedef struct AffinePoint {
    sp_int x, y;
    int atInfinity;
} AffinePoint;

static int affineInit(AffinePoint* point)
{
    point->atInfinity = 1;
    return sp_init(&point->x) == 0 ? sp_init(&point->y) : MP_MEM;
}

static int affineSetBytes(AffinePoint* point, const unsigned char* raw65)
{
    char xHex[65], yHex[65];
    static const char digits[] = "0123456789abcdef";
    int i;
    if (raw65[0] != 0x04)
        return BAD_FUNC_ARG;
    for (i = 0; i < 32; i++) {
        xHex[i * 2] = digits[raw65[1 + i] >> 4];
        xHex[i * 2 + 1] = digits[raw65[1 + i] & 0x0F];
        yHex[i * 2] = digits[raw65[33 + i] >> 4];
        yHex[i * 2 + 1] = digits[raw65[33 + i] & 0x0F];
    }
    xHex[64] = '\0';
    yHex[64] = '\0';
    point->atInfinity = 0;
    return sp_read_radix(&point->x, xHex, 16) == 0
        ? sp_read_radix(&point->y, yHex, 16) : MP_VAL;
}

/* q = q + p over the short-Weierstrass curve (affine, mod p). */
static int affineAdd(const AffinePoint* p, AffinePoint* q)
{
    sp_int lambda, x3, y3, tmp, t1, t2;
    int ok = sp_init(&lambda) == 0 && sp_init(&x3) == 0 && sp_init(&y3) == 0 &&
        sp_init(&tmp) == 0 && sp_init(&t1) == 0 && sp_init(&t2) == 0;
    int rc;

    if (!ok)
        return MP_MEM;

    if (q->atInfinity) {
        /* q + infinity = p: adopt p's coordinates. */
        q->atInfinity = 0;
        rc = sp_copy(&p->x, &q->x);
        if (rc == 0)
            rc = sp_copy(&p->y, &q->y);
        return rc;
    }
    if (p->atInfinity)
        return 0; /* q + infinity = q */

    if (sp_cmp(&p->x, &q->x) == 0 && sp_cmp(&p->y, &q->y) == 0) {
        /* doubling: lambda = (3x^2 + a) / (2y) */
        rc = sp_mulmod(&p->x, &p->x, &zt_p, &t1);            /* t1 = x^2 */
        if (rc == 0) rc = sp_addmod(&t1, &t1, &zt_p, &t2);   /* t2 = 2x^2 */
        if (rc == 0) rc = sp_addmod(&t2, &t1, &zt_p, &t1);   /* t1 = 3x^2 */
        if (rc == 0) rc = sp_addmod(&t1, &zt_a, &zt_p, &t2); /* t2 = 3x^2+a */
        if (rc == 0) rc = sp_addmod(&p->y, &p->y, &zt_p, &t1); /* t1 = 2y */
        if (rc == 0) rc = sp_invmod(&t1, &zt_p, &t1);        /* t1 = 1/(2y) */
        if (rc == 0) rc = sp_mulmod(&t2, &t1, &zt_p, &lambda);
    }
    else {
        /* addition: lambda = (qy - py) / (qx - px) */
        rc = sp_submod(&q->y, &p->y, &zt_p, &t1);
        if (rc == 0) rc = sp_submod(&q->x, &p->x, &zt_p, &t2);
        if (rc == 0) rc = sp_invmod(&t2, &zt_p, &t2);
        if (rc == 0) rc = sp_mulmod(&t1, &t2, &zt_p, &lambda);
    }

    if (rc == 0) rc = sp_mulmod(&lambda, &lambda, &zt_p, &x3);
    if (rc == 0) rc = sp_submod(&x3, &p->x, &zt_p, &t1);
    if (rc == 0) rc = sp_submod(&t1, &q->x, &zt_p, &x3);
    if (rc == 0) rc = sp_submod(&p->x, &x3, &zt_p, &t2);
    if (rc == 0) rc = sp_mulmod(&lambda, &t2, &zt_p, &y3);
    if (rc == 0) rc = sp_submod(&y3, &p->y, &zt_p, &y3);
    if (rc == 0) rc = sp_copy(&x3, &q->x);
    if (rc == 0) rc = sp_copy(&y3, &q->y);
    return rc;
}

/* out32 = big-endian X coordinate of (scalarHex * point65). The scalar is
 * materialized once via sp_to_unsigned_bin (32 big-endian bytes) and then
 * consumed MSB-first with plain double-and-add. */
static int scalarMulHex(const char* scalarHex, const unsigned char* point65,
                        unsigned char* out32)
{
    AffinePoint generator, accumulator;
    unsigned char scalarBytes[32];
    unsigned char scalarCopy[32];
    sp_int readback;
    int byteIdx, bitIdx, written, rc;

    rc = sp_init(&readback);
    if (rc == 0)
        rc = affineInit(&generator);
    if (rc == 0)
        rc = affineInit(&accumulator);
    if (rc == 0)
        rc = sp_read_radix(&readback, scalarHex, 16);
    if (rc != 0)
        return rc;
    /* sp_to_unsigned_bin writes minimal big-endian length; right-align into
     * exactly 32 bytes. */
    memset(scalarCopy, 0, sizeof(scalarCopy));
    rc = sp_to_unsigned_bin(&readback, scalarBytes);
    if (rc == 0) {
        written = (int)sp_unsigned_bin_size(&readback);
        if (written <= 0 || written > 32)
            return BUFFER_E;
        memcpy(scalarCopy + (32 - written), scalarBytes, (size_t)written);
    }
    if (rc == 0)
        rc = affineSetBytes(&generator, point65);
    if (rc != 0)
        return rc;

    for (byteIdx = 0; byteIdx < 32 && rc == 0; byteIdx++) {
        for (bitIdx = 7; bitIdx >= 0 && rc == 0; bitIdx--) {
            if (!accumulator.atInfinity)
                rc = affineAdd(&accumulator, &accumulator);
            if (rc == 0 && ((scalarCopy[byteIdx] >> bitIdx) & 1) != 0)
                rc = affineAdd(&generator, &accumulator);
        }
    }
    if (rc == 0) {
        if (accumulator.atInfinity)
            return BAD_STATE_E;
        memset(out32, 0, 32);
        rc = sp_to_unsigned_bin(&accumulator.x, scalarBytes);
        if (rc == 0) {
            written = (int)sp_unsigned_bin_size(&accumulator.x);
            if (written <= 0 || written > 32)
                return BUFFER_E;
            memcpy(out32 + (32 - written), scalarBytes, (size_t)written);
        }
    }
    return rc;
}

/* --- bridges ------------------------------------------------------------ */

struct SoftBridge {
    const char* scalarHex;
    int forcedError; /* when nonzero, agree returns this instead */
    int calls;
};

static int softAgree(void* ctxPointer, const unsigned char* peerPoint,
                     unsigned char* out)
{
    struct SoftBridge* ctx = (struct SoftBridge*)ctxPointer;
    ctx->calls++;
    if (ctx->forcedError != 0)
        return ctx->forcedError;
    return scalarMulHex(ctx->scalarHex, peerPoint, out);
}

/* An ECDH answer that deliberately returns a hard negative (never
 * CRYPTOCB_UNAVAILABLE), proving hard errors propagate. */
static int hardFailingAgree(void* ctxPointer, const unsigned char* peerPoint,
                            unsigned char* out)
{
    (void)ctxPointer;
    (void)peerPoint;
    (void)out;
    return -333; /* arbitrary, in the wolfSSL negative error range */
}

/* --- test helpers ------------------------------------------------------- */

static int failures = 0;

static void expect(int condition, const char* name)
{
    if (condition) {
        printf("ok %s\n", name);
    }
    else {
        printf("FAIL %s\n", name);
        failures++;
    }
}

static int sharedSecretViaCallback(ecc_key* priv, ecc_key* pub,
                                   unsigned char* out, word32* outLen)
{
    return wc_ecc_shared_secret(priv, pub, out, outLen);
}

int main(void)
{
    unsigned char enc[65], ct[48], pt[64], shared[32];
    const size_t infoSz = sizeof(INFO_TEXT) - 1;
    const size_t aadSz = sizeof(AAD_TEXT) - 1;
    struct SoftBridge softBridge;
    struct zt_hpke_bridge bridge;
    int ret;

    unsigned char pkR[65];
    if (hexDecode(ENC_HEX, enc, sizeof(enc)) != ENC_LEN ||
        hexDecode(CT_HEX, ct, sizeof(ct)) != CT_LEN ||
        hexDecode(SHARED_SECRET_HEX, shared, sizeof(shared)) != 32 ||
        hexDecode(PK_R_HEX, pkR, sizeof(pkR)) != ENC_LEN) {
        printf("FAIL vector decoding\n");
        return 1;
    }

    ret = wolfCrypt_Init();
    if (ret != 0) {
        printf("FAIL wolfCrypt_Init (%d)\n", ret);
        return 1;
    }
    /* Mirror the production JNI_OnLoad: the crypto device is registered once
     * per process before any key operation. */
    ret = zt_hpke_init();
    if (ret != 0) {
        printf("FAIL zt_hpke_init (%d)\n", ret);
        return 1;
    }
    if (fieldSetup() != 0) {
        printf("FAIL field setup\n");
        return 1;
    }

    memset(&softBridge, 0, sizeof(softBridge));
    softBridge.scalarHex = SK_R_HEX;
    bridge.agree = softAgree;
    bridge.ctx = &softBridge;

    /* 1. The callback contract produces the RFC shared secret exactly:
     * ANSI X9.63 output = 32-byte big-endian X coordinate. */
    {
        ecc_key priv, peer;
        unsigned char dh[32];
        word32 dhLen = sizeof(dh);
        ret = wc_ecc_init_ex(&priv, NULL, 0x5A544B31);
        if (ret == 0)
            ret = wc_ecc_init(&peer);
        if (ret == 0) {
            /* A device-key handle carries its curve parameters but no
             * software key material, exactly like the production receiver
             * key after its public-point import. */
            ret = wc_ecc_set_curve(&priv, 32, ECC_SECP256R1);
        }
        if (ret == 0)
            priv.devId = 0x5A544B31;
        if (ret == 0) {
            priv.devCtx = &bridge;
            ret = wc_ecc_import_x963_ex(enc, 65, &peer, ECC_SECP256R1);
        }
        if (ret == 0)
            ret = sharedSecretViaCallback(&priv, &peer, dh, &dhLen);
        expect(ret == 0 && dhLen == 32 &&
               memcmp(dh, shared, 32) == 0,
               "callback produces rfc9180 shared secret");
        expect(softBridge.calls == 1, "callback invoked exactly once");
        if (ret == 0) wc_ForceZero(dh, sizeof(dh));
        wc_ecc_free(&peer);
        wc_ecc_free(&priv);
    }

    /* 2. The full core open on the RFC vector. */
    {
        unsigned char ptBuf[64];
        memset(ptBuf, 0, sizeof(ptBuf));
        ret = zt_hpke_open(&bridge, pkR, ENC_LEN, enc, ENC_LEN, ct, CT_LEN,
            (const unsigned char*)INFO_TEXT, infoSz,
            (const unsigned char*)AAD_TEXT, aadSz, ptBuf, CT_LEN - 16);
        expect(ret == 0 &&
               memcmp(ptBuf, PLAINTEXT_TEXT, PT_LEN) == 0,
               "rfc9180 vector opens through bridge core");
        wc_ForceZero(ptBuf, (word32)sizeof(ptBuf));
    }

    /* 3. Cross-client rejections: tampered tag, changed info/aad, wrong key. */
    {
        unsigned char bad[64], ptBuf[64];
        memcpy(bad, ct, CT_LEN);
        bad[CT_LEN - 1] ^= 1;
        ret = zt_hpke_open(&bridge, pkR, ENC_LEN, enc, ENC_LEN, bad, CT_LEN,
            (const unsigned char*)INFO_TEXT, infoSz,
            (const unsigned char*)AAD_TEXT, aadSz, ptBuf, CT_LEN - 16);
        expect(ret < 0, "tampered tag rejected");
    }
    {
        unsigned char ptBuf[64];
        ret = zt_hpke_open(&bridge, pkR, ENC_LEN, enc, ENC_LEN, ct, CT_LEN,
            (const unsigned char*)INFO_TEXT, infoSz + 1, /* wrong info */
            (const unsigned char*)AAD_TEXT, aadSz, ptBuf, CT_LEN - 16);
        expect(ret < 0, "changed info rejected");
    }
    {
        unsigned char ptBuf[64];
        ret = zt_hpke_open(&bridge, pkR, ENC_LEN, enc, ENC_LEN, ct, CT_LEN,
            (const unsigned char*)INFO_TEXT, infoSz,
            (const unsigned char*)AAD_TEXT, aadSz + 1, /* wrong aad */
            ptBuf, CT_LEN - 16);
        expect(ret < 0, "changed aad rejected");
    }
    {
        struct SoftBridge wrongKey;
        struct zt_hpke_bridge wrongBridge;
        unsigned char ptBuf[64];
        memset(&wrongKey, 0, sizeof(wrongKey));
        wrongKey.scalarHex =
            "f4ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2";
        wrongBridge.agree = softAgree;
        wrongBridge.ctx = &wrongKey;
        ret = zt_hpke_open(&wrongBridge, pkR, ENC_LEN, enc, ENC_LEN, ct, CT_LEN,
            (const unsigned char*)INFO_TEXT, infoSz,
            (const unsigned char*)AAD_TEXT, aadSz, ptBuf, CT_LEN - 16);
        expect(ret < 0, "wrong recipient key rejected");
    }

    /* 4. Wrapper framing checks (binding condition 3). */
    {
        unsigned char ptBuf[64];
        ret = zt_hpke_open(&bridge, pkR, ENC_LEN, enc, ENC_LEN - 1, ct, CT_LEN,
            (const unsigned char*)INFO_TEXT, infoSz,
            (const unsigned char*)AAD_TEXT, aadSz, ptBuf, CT_LEN - 16);
        expect(ret < 0, "64-byte enc rejected");
    }
    {
        unsigned char ptBuf[64];
        ret = zt_hpke_open(&bridge, pkR, ENC_LEN, enc, ENC_LEN + 1, ct, CT_LEN,
            (const unsigned char*)INFO_TEXT, infoSz,
            (const unsigned char*)AAD_TEXT, aadSz, ptBuf, CT_LEN - 16);
        expect(ret < 0, "66-byte enc rejected");
    }
    {
        unsigned char ptBuf[64];
        ret = zt_hpke_open(&bridge, pkR, ENC_LEN, enc, ENC_LEN, ct, 16,
            (const unsigned char*)INFO_TEXT, infoSz,
            (const unsigned char*)AAD_TEXT, aadSz, ptBuf, 0);
        expect(ret < 0, "16-byte ciphertext rejected");
    }
    {
        unsigned char ptBuf[64];
        ret = zt_hpke_open(&bridge, pkR, ENC_LEN, enc, ENC_LEN, ct, CT_LEN,
            (const unsigned char*)INFO_TEXT, 0,
            (const unsigned char*)AAD_TEXT, aadSz, ptBuf, CT_LEN - 16);
        expect(ret < 0, "empty info rejected");
    }
    {
        unsigned char ptBuf[64];
        ret = zt_hpke_open(&bridge, pkR, ENC_LEN, enc, ENC_LEN, ct, CT_LEN,
            (const unsigned char*)INFO_TEXT, infoSz,
            (const unsigned char*)AAD_TEXT, 0, ptBuf, CT_LEN - 16);
        expect(ret < 0, "empty aad rejected");
    }
    {
        unsigned char ptBuf[64];
        ret = zt_hpke_open(&bridge, pkR, ENC_LEN, enc, ENC_LEN, ct, CT_LEN,
            (const unsigned char*)INFO_TEXT, infoSz,
            (const unsigned char*)INFO_TEXT, infoSz, ptBuf, CT_LEN - 16);
        expect(ret < 0, "info equal to aad rejected");
    }
    {
        unsigned char ptBuf[64];
        ret = zt_hpke_open(&bridge, pkR, ENC_LEN, enc, ENC_LEN, ct, CT_LEN,
            (const unsigned char*)INFO_TEXT, infoSz,
            (const unsigned char*)AAD_TEXT, aadSz, ptBuf, CT_LEN - 17);
        expect(ret < 0, "undersized plaintext buffer rejected");
    }

    /* 5. Binding condition 1: software ECDH does not exist in this build.
     * A key initialized without a registered device must fail with
     * NO_VALID_DEVID, not compute in software. */
    {
        ecc_key priv, peer;
        unsigned char dh[32];
        word32 dhLen = sizeof(dh);
        ret = wc_ecc_init(&priv);
        if (ret == 0)
            ret = wc_ecc_init(&peer);
        if (ret == 0)
            ret = wc_ecc_import_x963_ex(enc, 65, &peer, ECC_SECP256R1);
        if (ret == 0)
            ret = sharedSecretViaCallback(&priv, &peer, dh, &dhLen);
        expect(ret == NO_VALID_DEVID, "unregistered key fails closed NO_VALID_DEVID");
        wc_ecc_free(&peer);
        wc_ecc_free(&priv);
    }

    /* 6. Binding condition 2: a callback hard error propagates; it is not
     * swallowed and does not reach any software fallback. */
    {
        ecc_key priv, peer;
        unsigned char dh[32];
        word32 dhLen = sizeof(dh);
        ret = wc_ecc_init_ex(&priv, NULL, 0x5A544B31);
        if (ret == 0)
            ret = wc_ecc_init(&peer);
        if (ret == 0)
            ret = wc_ecc_set_curve(&priv, 32, ECC_SECP256R1);
        if (ret == 0)
            priv.devId = 0x5A544B31;
        if (ret == 0) {
            priv.devCtx = NULL; /* callback guard: BAD_STATE_E */
            ret = wc_ecc_import_x963_ex(enc, 65, &peer, ECC_SECP256R1);
        }
        if (ret == 0)
            ret = sharedSecretViaCallback(&priv, &peer, dh, &dhLen);
        expect(ret == BAD_STATE_E, "missing per-open context fails hard");
        wc_ecc_free(&peer);
        wc_ecc_free(&priv);
    }
    {
        ecc_key priv, peer;
        unsigned char dh[32];
        word32 dhLen = sizeof(dh);
        ret = wc_ecc_init_ex(&priv, NULL, 0x5A544B31);
        if (ret == 0)
            ret = wc_ecc_init(&peer);
        if (ret == 0)
            ret = wc_ecc_set_curve(&priv, 32, ECC_SECP256R1);
        if (ret == 0)
            priv.devId = 0x5A544B31;
        if (ret == 0)
            ret = wc_ecc_import_x963_ex(enc, 65, &peer, ECC_SECP256R1);
        if (ret == 0) {
            /* Route the callback through zt_hpke_open's registered handler
             * with a bridge whose agree returns a hard negative. */
            struct zt_hpke_bridge failing;
            failing.agree = hardFailingAgree;
            failing.ctx = NULL;
            priv.devCtx = &failing;
            ret = sharedSecretViaCallback(&priv, &peer, dh, &dhLen);
        }
        expect(ret == -333, "callback hard error propagates unchanged");
        wc_ecc_free(&peer);
        wc_ecc_free(&priv);
    }

    /* 7. An ephemeral point that is not on P-256 does not validate at
     * import (this build deliberately does not dispatch import-time point
     * validation; see user_settings.h) — it is refused at open instead:
     * the wrong DH feeds the key schedule and the AEAD tag fails. */
    {
        unsigned char offCurve[65], ptBuf[64];
        memcpy(offCurve, enc, 65);
        offCurve[64] ^= 1; /* invalidates curve membership */
        ret = zt_hpke_open(&bridge, pkR, ENC_LEN, offCurve, ENC_LEN, ct, CT_LEN,
            (const unsigned char*)INFO_TEXT, infoSz,
            (const unsigned char*)AAD_TEXT, aadSz, ptBuf, CT_LEN - 16);
        expect(ret < 0, "off-curve ephemeral rejected at open");
    }

    wolfCrypt_Cleanup();
    if (failures != 0) {
        printf("%d test(s) FAILED\n", failures);
        return 1;
    }
    printf("all bridge known-answer tests passed\n");
    return 0;
}
