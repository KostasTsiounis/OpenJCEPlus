/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <openssl/evp.h>

#include "com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation.h"
#include "Utils.h"
#include <stdint.h>

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    PQC_SIGNATURE_sign
 * Signature: (JJ[B)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_PQC_1SIGNATURE_1sign(
    JNIEnv *env, jclass thisObj, jlong osslContextId, jlong pKeyId,
    jbyteArray data) {

    EVP_PKEY         *pkey           = (EVP_PKEY *)((intptr_t)pKeyId);
    EVP_PKEY_CTX     *ctx            = NULL;
    unsigned char    *dataNative     = NULL;
    unsigned char    *sigBuf         = NULL;
    unsigned char    *sigBytesNative = NULL;
    jbyteArray        sigBytes       = NULL;
    jboolean          isCopy         = 0;
    size_t            dataLen        = 0;
    size_t            sigLen         = 0;
    int               rc             = 0;
    jbyteArray        retSigBytes    = NULL;

    if (pkey == NULL || data == NULL) {
        throwOSSLException(env, 0, "PQC_SIGNATURE_sign: pkey or data is null");
        return NULL;
    }

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    if (ctx == NULL) {
        throwOSSLException(env, 0, "PQC_SIGNATURE_sign: EVP_PKEY_CTX_new_from_pkey failed");
        return NULL;
    }

    if (1 != EVP_PKEY_sign_init(ctx)) {
        throwOSSLException(env, 0, "PQC_SIGNATURE_sign: EVP_PKEY_sign_init failed");
        goto cleanup;
    }

    dataLen    = (size_t)((*env)->GetArrayLength(env, data));
    dataNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, data, &isCopy));
    if (dataNative == NULL) {
        throwOSSLException(env, 0, "PQC_SIGNATURE_sign: GetPrimitiveArrayCritical failed");
        goto cleanup;
    }

    /* Determine signature length */
    rc = EVP_PKEY_sign(ctx, NULL, &sigLen, dataNative, dataLen);
    if (1 != rc || sigLen == 0) {
        (*env)->ReleasePrimitiveArrayCritical(env, data, dataNative, JNI_ABORT);
        throwOSSLException(env, 0, "PQC_SIGNATURE_sign: EVP_PKEY_sign (size query) failed");
        goto cleanup;
    }

    sigBuf = (unsigned char *)malloc(sigLen);
    if (sigBuf == NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, data, dataNative, JNI_ABORT);
        throwOSSLException(env, 0, "PQC_SIGNATURE_sign: malloc failed");
        goto cleanup;
    }

    rc = EVP_PKEY_sign(ctx, sigBuf, &sigLen, dataNative, dataLen);
    (*env)->ReleasePrimitiveArrayCritical(env, data, dataNative, JNI_ABORT);
    dataNative = NULL;

    if (1 != rc) {
        throwOSSLException(env, 0, "PQC_SIGNATURE_sign: EVP_PKEY_sign failed");
        goto cleanup;
    }

    sigBytes = (*env)->NewByteArray(env, (jsize)sigLen);
    if (sigBytes == NULL) {
        throwOSSLException(env, 0, "PQC_SIGNATURE_sign: NewByteArray failed");
        goto cleanup;
    }

    sigBytesNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, sigBytes, &isCopy));
    if (sigBytesNative == NULL) {
        throwOSSLException(env, 0, "PQC_SIGNATURE_sign: GetPrimitiveArrayCritical (sig) failed");
        goto cleanup;
    }

    memcpy(sigBytesNative, sigBuf, sigLen);
    (*env)->ReleasePrimitiveArrayCritical(env, sigBytes, sigBytesNative, 0);
    retSigBytes = sigBytes;

cleanup:
    if (ctx != NULL) {
        EVP_PKEY_CTX_free(ctx);
    }
    if (sigBuf != NULL) {
        free(sigBuf);
    }
    if ((sigBytes != NULL) && (retSigBytes == NULL)) {
        (*env)->DeleteLocalRef(env, sigBytes);
    }
    return retSigBytes;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation
 * Method:    PQC_SIGNATURE_verify
 * Signature: (JJ[B[B)Z
 */
JNIEXPORT jboolean JNICALL
Java_com_ibm_crypto_plus_provider_openssl_NativeOpenSSLImplementation_PQC_1SIGNATURE_1verify(
    JNIEnv *env, jclass thisObj, jlong osslContextId, jlong pKeyId,
    jbyteArray sigBytes, jbyteArray data) {

    EVP_PKEY         *pkey           = (EVP_PKEY *)((intptr_t)pKeyId);
    EVP_PKEY_CTX     *ctx            = NULL;
    unsigned char    *sigBytesNative = NULL;
    unsigned char    *dataNative     = NULL;
    jboolean          isCopy         = 0;
    size_t            sigLen         = 0;
    size_t            dataLen        = 0;
    int               rc             = 0;
    jboolean          verified       = JNI_FALSE;

    if (pkey == NULL || sigBytes == NULL || data == NULL) {
        throwOSSLException(env, 0, "PQC_SIGNATURE_verify: pkey, sigBytes, or data is null");
        return JNI_FALSE;
    }

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    if (ctx == NULL) {
        throwOSSLException(env, 0, "PQC_SIGNATURE_verify: EVP_PKEY_CTX_new_from_pkey failed");
        return JNI_FALSE;
    }

    if (1 != EVP_PKEY_verify_init(ctx)) {
        throwOSSLException(env, 0, "PQC_SIGNATURE_verify: EVP_PKEY_verify_init failed");
        goto cleanup;
    }

    sigLen         = (size_t)((*env)->GetArrayLength(env, sigBytes));
    sigBytesNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, sigBytes, &isCopy));
    if (sigBytesNative == NULL) {
        throwOSSLException(env, 0, "PQC_SIGNATURE_verify: GetPrimitiveArrayCritical (sig) failed");
        goto cleanup;
    }

    dataLen    = (size_t)((*env)->GetArrayLength(env, data));
    dataNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(env, data, &isCopy));
    if (dataNative == NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, sigBytes, sigBytesNative, JNI_ABORT);
        throwOSSLException(env, 0, "PQC_SIGNATURE_verify: GetPrimitiveArrayCritical (data) failed");
        goto cleanup;
    }

    rc = EVP_PKEY_verify(ctx, sigBytesNative, sigLen, dataNative, dataLen);

    (*env)->ReleasePrimitiveArrayCritical(env, data, dataNative, JNI_ABORT);
    (*env)->ReleasePrimitiveArrayCritical(env, sigBytes, sigBytesNative, JNI_ABORT);

    if (rc == 1) {
        verified = JNI_TRUE;
    } else {
        throwOSSLException(env, 0, "PQC_SIGNATURE_verify: EVP_PKEY_verify failed");
    }

cleanup:
    if (ctx != NULL) {
        EVP_PKEY_CTX_free(ctx);
    }
    return verified;
}
