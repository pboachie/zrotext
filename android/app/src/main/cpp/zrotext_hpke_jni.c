// SPDX-License-Identifier: AGPL-3.0-only
/* JNI adapter between the wolfSSL crypto callback and AndroidKeyStore.
 *
 * The recipient private key never enters this library: the adapter hands the
 * peer's 65-byte public point to Kotlin, which performs exactly one
 * KeyAgreement("ECDH") operation on the AndroidKeyStore PURPOSE_AGREE_KEY
 * object and returns the 32-byte X coordinate. The Kotlin side zeroes its
 * copy of that per-message transient; wolfSSL zeroes the KEM copy after
 * ExtractAndExpand (hpke.c ForceZero(dh, hpke->Ndh)).
 *
 * Every failure path here returns a hard negative wolfSSL error code from
 * the crypto callback. CRYPTOCB_UNAVAILABLE is never returned (binding
 * condition 2 of the #1003 provider selection); Java exceptions raised by
 * the Keystore operation are surfaced as BAD_STATE_E.
 */
#include <jni.h>
#include <stdlib.h>
#include <string.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/wc_port.h>

#include "zrotext_hpke_core.h"

#define ZT_PEER_POINT_LEN 65
#define ZT_SHARED_SECRET_LEN 32

typedef struct JniBridge {
    JNIEnv* env;
    jobject receiver;
    jmethodID agreeMethod;
    jobject privateKey;
} JniBridge;

/* org.zrotext.gateway.WolfHpkeKeystoreReceiver private instance callback:
 * private fun agreeFromNative(privateKey: PrivateKey, peerPoint: ByteArray) */
static const char* AGREE_METHOD_NAME = "agreeFromNative";
static const char* AGREE_METHOD_SIG = "(Ljava/security/PrivateKey;[B)[B";

static void throwSecurity(JNIEnv* env, const char* message)
{
    jclass cls = (*env)->FindClass(env, "java/security/GeneralSecurityException");
    if (cls != NULL)
        (*env)->ThrowNew(env, cls, message);
}

static int jni_agree(void* ctxPointer, const unsigned char* peerPoint,
                     unsigned char* out)
{
    JniBridge* bridge = (JniBridge*)ctxPointer;
    JNIEnv* env = bridge->env;
    jbyteArray peer = NULL;
    jbyteArray agreed = NULL;
    jbyte* elements = NULL;
    jsize length;
    int rc = BAD_STATE_E;

    peer = (*env)->NewByteArray(env, ZT_PEER_POINT_LEN);
    if (peer == NULL || (*env)->ExceptionCheck(env)) {
        if ((*env)->ExceptionCheck(env))
            (*env)->ExceptionClear(env);
        return BAD_STATE_E;
    }
    (*env)->SetByteArrayRegion(env, peer, 0, ZT_PEER_POINT_LEN,
        (const jbyte*)peerPoint);

    agreed = (jbyteArray)(*env)->CallObjectMethod(env, bridge->receiver,
        bridge->agreeMethod, bridge->privateKey, peer);
    (*env)->DeleteLocalRef(env, peer);
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        return BAD_STATE_E;
    }
    if (agreed == NULL)
        return BAD_STATE_E;

    length = (*env)->GetArrayLength(env, agreed);
    if (length != ZT_SHARED_SECRET_LEN) {
        rc = ECC_BAD_ARG_E;
        goto done;
    }
    elements = (*env)->GetByteArrayElements(env, agreed, NULL);
    if (elements == NULL)
        goto done;
    memcpy(out, elements, ZT_SHARED_SECRET_LEN);
    /* The shared secret is a per-message transient: zero the JVM-side copy
     * before returning it to wolfSSL's key schedule. */
    memset(elements, 0, (size_t)ZT_SHARED_SECRET_LEN);
    (*env)->ReleaseByteArrayElements(env, agreed, elements, 0);
    elements = NULL;
    rc = 0;

done:
    if (elements != NULL)
        (*env)->ReleaseByteArrayElements(env, agreed, elements, JNI_ABORT);
    (*env)->DeleteLocalRef(env, agreed);
    return rc;
}

JNIEXPORT jbyteArray JNICALL
Java_org_zrotext_gateway_WolfHpkeKeystoreReceiver_nativeOpen(
    JNIEnv* env, jobject receiver, jobject privateKey, jbyteArray jRecipient,
    jbyteArray jEnc, jbyteArray jCt, jbyteArray jInfo, jbyteArray jAad)
{
    static jmethodID agreeMethod = NULL;
    JniBridge bridge;
    struct zt_hpke_bridge coreBridge;
    jbyte* recipient = NULL;
    jbyte* enc = NULL;
    jbyte* ct = NULL;
    jbyte* info = NULL;
    jbyte* aad = NULL;
    unsigned char* pt = NULL;
    jsize recipientSz, encSz, ctSz, infoSz, aadSz;
    jsize ptSz;
    jbyteArray result = NULL;
    int ret;

    if (agreeMethod == NULL) {
        agreeMethod = (*env)->GetMethodID(env,
            (*env)->GetObjectClass(env, receiver),
            AGREE_METHOD_NAME, AGREE_METHOD_SIG);
        if (agreeMethod == NULL)
            return NULL;
    }

    recipientSz = (*env)->GetArrayLength(env, jRecipient);
    encSz = (*env)->GetArrayLength(env, jEnc);
    ctSz = (*env)->GetArrayLength(env, jCt);
    infoSz = (*env)->GetArrayLength(env, jInfo);
    aadSz = (*env)->GetArrayLength(env, jAad);
    if (ctSz < 17 || recipientSz < 0 || encSz < 0 || infoSz < 0 || aadSz < 0) {
        throwSecurity(env, "HPKE open rejected");
        return NULL;
    }
    ptSz = ctSz - 16;
    pt = (unsigned char*)malloc((size_t)ptSz);
    if (pt == NULL) {
        throwSecurity(env, "HPKE open rejected");
        return NULL;
    }
    memset(pt, 0, (size_t)ptSz);

    recipient = (*env)->GetByteArrayElements(env, jRecipient, NULL);
    enc = (*env)->GetByteArrayElements(env, jEnc, NULL);
    ct = (*env)->GetByteArrayElements(env, jCt, NULL);
    info = (*env)->GetByteArrayElements(env, jInfo, NULL);
    aad = (*env)->GetByteArrayElements(env, jAad, NULL);
    if (recipient == NULL || enc == NULL || ct == NULL || info == NULL ||
        aad == NULL)
        goto fail;

    bridge.env = env;
    bridge.receiver = receiver;
    bridge.agreeMethod = agreeMethod;
    bridge.privateKey = privateKey;
    coreBridge.agree = jni_agree;
    coreBridge.ctx = &bridge;

    ret = zt_hpke_open(&coreBridge,
        (const unsigned char*)recipient, (size_t)recipientSz,
        (const unsigned char*)enc, (size_t)encSz,
        (const unsigned char*)ct, (size_t)ctSz,
        (const unsigned char*)info, (size_t)infoSz,
        (const unsigned char*)aad, (size_t)aadSz,
        pt, (size_t)ptSz);

    (*env)->ReleaseByteArrayElements(env, jRecipient, recipient, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, jEnc, enc, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, jCt, ct, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, jInfo, info, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, jAad, aad, JNI_ABORT);
    recipient = enc = ct = info = aad = NULL;

    if (ret != 0) {
        throwSecurity(env, "HPKE open rejected");
        goto fail;
    }

    result = (*env)->NewByteArray(env, ptSz);
    if (result != NULL)
        (*env)->SetByteArrayRegion(env, result, 0, ptSz, (const jbyte*)pt);
    memset(pt, 0, (size_t)ptSz);
    free(pt);
    return result;

fail:
    if (recipient != NULL) (*env)->ReleaseByteArrayElements(env, jRecipient, recipient, JNI_ABORT);
    if (enc != NULL) (*env)->ReleaseByteArrayElements(env, jEnc, enc, JNI_ABORT);
    if (ct != NULL) (*env)->ReleaseByteArrayElements(env, jCt, ct, JNI_ABORT);
    if (info != NULL) (*env)->ReleaseByteArrayElements(env, jInfo, info, JNI_ABORT);
    if (aad != NULL) (*env)->ReleaseByteArrayElements(env, jAad, aad, JNI_ABORT);
    if (pt != NULL) {
        memset(pt, 0, (size_t)ptSz);
        free(pt);
    }
    return NULL;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved)
{
    JNIEnv* env = NULL;
    (void)reserved;
    if ((*vm)->GetEnv(vm, (void**)&env, JNI_VERSION_1_6) != JNI_OK)
        return JNI_ERR;
    if (wolfCrypt_Init() != 0)
        return JNI_ERR;
    if (zt_hpke_init() != 0)
        return JNI_ERR;
    return JNI_VERSION_1_6;
}

JNIEXPORT void JNICALL JNI_OnUnload(JavaVM* vm, void* reserved)
{
    JNIEnv* env = NULL;
    (void)reserved;
    zt_hpke_deinit();
    if ((*vm)->GetEnv(vm, (void**)&env, JNI_VERSION_1_6) == JNI_OK)
        wolfCrypt_Cleanup();
}
