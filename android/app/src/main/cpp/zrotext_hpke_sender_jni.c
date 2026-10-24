// SPDX-License-Identifier: AGPL-3.0-only
/* Sender-only JNI. Recipient and ephemeral inputs are public points; the one-use
 * ephemeral JCA private OBJECT answers the existing callback. No identity scalar,
 * recipient private material, native software ECDH or fallback is introduced. */
#include <jni.h>
#include <string.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/memory.h>
#include "zrotext_hpke_core.h"

typedef struct SenderBridge {
    JNIEnv* env;
    jobject sender;
    jobject privateKey;
    jmethodID agree;
} SenderBridge;

static int sender_agree(void* pointer, const unsigned char* peerPoint,
                        unsigned char* out)
{
    SenderBridge* b = (SenderBridge*)pointer;
    JNIEnv* env = b->env;
    jbyteArray peer = NULL;
    jbyteArray dhArray = NULL;
    jbyte* bytes = NULL;
    jsize secretSz = 0;
    int rc = BAD_STATE_E;
    peer = (*env)->NewByteArray(env, 65);
    if (peer == NULL || (*env)->ExceptionCheck(env))
        goto done;
    (*env)->SetByteArrayRegion(env, peer, 0, 65, (const jbyte*)peerPoint);
    if ((*env)->ExceptionCheck(env))
        goto done;
    dhArray = (jbyteArray)(*env)->CallObjectMethod(env, b->sender, b->agree,
                                               b->privateKey, peer);
    if ((*env)->ExceptionCheck(env) || dhArray == NULL)
        goto done;
    secretSz = (*env)->GetArrayLength(env, dhArray);
    bytes = (*env)->GetByteArrayElements(env, dhArray, NULL);
    if (bytes == NULL || secretSz != 32)
        goto done;
    memcpy(out, bytes, 32U);
    wc_ForceZero(bytes, 32U);
    (*env)->ReleaseByteArrayElements(env, dhArray, bytes, 0);
    bytes = NULL;
    rc = 0;
done:
    if (bytes != NULL) {
        wc_ForceZero(bytes, (word32)secretSz);
        (*env)->ReleaseByteArrayElements(env, dhArray, bytes, 0);
    }
    if (peer != NULL) (*env)->DeleteLocalRef(env, peer);
    if (dhArray != NULL) (*env)->DeleteLocalRef(env, dhArray);
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    return rc; /* Always hard failure; never CRYPTOCB_UNAVAILABLE. */
}

JNIEXPORT jbyteArray JNICALL
Java_org_zrotext_gateway_WolfHpkePublicSender_nativeSeal(JNIEnv* env,
    jobject sender, jobject privateKey, jbyteArray jEnc, jbyteArray jRecipient,
    jbyteArray jCek, jbyteArray jInfo, jbyteArray jAad)
{
    SenderBridge bridge;
    struct zt_hpke_bridge core;
    jclass cls = NULL;
    jmethodID agree = NULL;
    jbyte *enc = NULL, *recipient = NULL, *cek = NULL, *info = NULL, *aad = NULL;
    jsize infoSz, aadSz;
    unsigned char ct[48];
    jbyteArray result = NULL;
    int rc = BAD_STATE_E;
    XMEMSET(ct, 0, sizeof(ct));
    if (privateKey == NULL || jEnc == NULL || jRecipient == NULL || jCek == NULL ||
        jInfo == NULL || jAad == NULL)
        goto done;
    infoSz = (*env)->GetArrayLength(env, jInfo);
    aadSz = (*env)->GetArrayLength(env, jAad);
    if ((*env)->GetArrayLength(env, jEnc) != 65 ||
        (*env)->GetArrayLength(env, jRecipient) != 65 ||
        (*env)->GetArrayLength(env, jCek) != 32 || infoSz < 1 || infoSz > 1024 ||
        aadSz < 1 || aadSz > 1024)
        goto done;
    cls = (*env)->GetObjectClass(env, sender);
    if (cls == NULL) goto done;
    agree = (*env)->GetMethodID(env, cls, "agreeFromNative",
                              "(Ljava/security/PrivateKey;[B)[B");
    if (agree == NULL) goto done;
    enc = (*env)->GetByteArrayElements(env, jEnc, NULL);
    recipient = (*env)->GetByteArrayElements(env, jRecipient, NULL);
    cek = (*env)->GetByteArrayElements(env, jCek, NULL);
    info = (*env)->GetByteArrayElements(env, jInfo, NULL);
    aad = (*env)->GetByteArrayElements(env, jAad, NULL);
    if (enc == NULL || recipient == NULL || cek == NULL || info == NULL || aad == NULL)
        goto done;
    bridge.env = env; bridge.sender = sender; bridge.privateKey = privateKey; bridge.agree = agree;
    core.agree = sender_agree; core.ctx = &bridge;
    rc = zt_hpke_seal_cek(&core, (const unsigned char*)enc, 65U,
        (const unsigned char*)recipient, 65U, (const unsigned char*)cek, 32U,
        (const unsigned char*)info, (size_t)infoSz, (const unsigned char*)aad,
        (size_t)aadSz, ct, sizeof(ct));
    if (rc == 0) {
        result = (*env)->NewByteArray(env, 48);
        if (result != NULL) (*env)->SetByteArrayRegion(env, result, 0, 48, (const jbyte*)ct);
    }
done:
    if (enc != NULL) (*env)->ReleaseByteArrayElements(env, jEnc, enc, JNI_ABORT);
    if (recipient != NULL) (*env)->ReleaseByteArrayElements(env, jRecipient, recipient, JNI_ABORT);
    if (cek != NULL) { wc_ForceZero(cek, 32U); (*env)->ReleaseByteArrayElements(env, jCek, cek, 0); }
    if (info != NULL) (*env)->ReleaseByteArrayElements(env, jInfo, info, JNI_ABORT);
    if (aad != NULL) (*env)->ReleaseByteArrayElements(env, jAad, aad, JNI_ABORT);
    if (cls != NULL) (*env)->DeleteLocalRef(env, cls);
    wc_ForceZero(ct, sizeof(ct));
    if (result == NULL && !(*env)->ExceptionCheck(env)) {
        jclass failure = (*env)->FindClass(env, "java/security/GeneralSecurityException");
        if (failure != NULL) { (*env)->ThrowNew(env, failure, "HPKE wrap refused"); (*env)->DeleteLocalRef(env, failure); }
    }
    return result;
}
