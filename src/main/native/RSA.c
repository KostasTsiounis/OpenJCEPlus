/*
 * Copyright IBM Corp. 2023
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

#include <jni.h>
#include <stdio.h>
#include <assert.h>
#include <jcc_a.h>
#include <icc.h>

#include "com_ibm_crypto_plus_provider_ock_NativeInterface.h"
#include "Utils.h"
#include "RSAPadding.h"
#include <stdint.h>

static int rsaPaddingMap(int rsaPaddingId);
static char * getDigestName(int mdId);
static int setPadding(ICC_CTX *icc_ctx, ICC_EVP_PKEY_CTX *ctx, char *padding);

/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    RSACIPHER_encrypt
 * Signature: (JJII[BII[BI)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_ock_NativeInterface_RSACIPHER_1encrypt(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong rsaKeyId,
    jint rsaPaddingId, jint mdId, jbyteArray plaintext, jint plaintextOff,
    jint plaintextLen, jbyteArray ciphertext, jint ciphertextOff) {
    static const char *functionName = "NativeInterface.RSACIPHER_encrypt";

    ICC_CTX          *ockCtx            = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_EVP_PKEY     *ockRSA            = (ICC_EVP_PKEY *)((intptr_t)rsaKeyId);
    ICC_EVP_PKEY_CTX *keyCtx            = NULL;
    unsigned char    *plaintextNative   = NULL;
    unsigned char    *ciphertextNative  = NULL;
    size_t           outLen             = 0;
    jboolean         isCopy;

    if (debug) {
        gslogFunctionEntry(functionName);
#ifdef DEBUG_RSA_DETAIL
        gslogMessage(
            "DETAIL_RSACIPHER rsaKeyId %lx rsaPaddingId %x mdId %x plaintextOff %d "
            "plaintextLen %d ciphertextOff %d",
            (long)rsaKeyId, rsaPaddingId, mdId, (int)plaintextOff, (int)plaintextLen,
            (int)ciphertextOff);
#endif
    }

    if ((ockRSA == NULL) || (plaintext == NULL) || (ciphertext == NULL) ||
        (plaintextOff < 0) || (plaintextOff > plaintextLen) ||
        (ciphertextOff < 0)) {
        throwOCKException(env, 0, "The RSA input parameters are incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return (jint) outLen;
    }

    keyCtx = ICC_EVP_PKEY_CTX_new(ockCtx, ockRSA, NULL);
    if (!keyCtx) {
        throwOCKException(env, 0, "Could not create RSA context.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return (jint) outLen;
    }

    int rc = ICC_EVP_PKEY_encrypt_init(ockCtx, keyCtx);
    if (rc != ICC_OSSL_SUCCESS) {
        throwOCKException(env, 0, "Could not initialize.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        goto cleanup;
    }


    if (-1 == setPadding(ockCtx, keyCtx, rsaPaddingId, mdId)) {
        throwOCKException(env, 0, "Could not set padding.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        goto cleanup;
    }

    plaintextNative  = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
        env, plaintext, &isCopy));
    ciphertextNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
        env, ciphertext, &isCopy));
    if (NULL == plaintextNative || NULL == ciphertextNative) {
#ifdef DEBUG_RSA_DETAIL
        if (debug) {
            gslogMessage(
                "DETAIL_RSACIPHER FAILURE plaintextNative or cihertextNative ");
        }
#endif
        throwOCKException(env, 0, "GetPrimitiveArrayCritical failed");

        goto cleanup;
    }
#ifdef DEBUG_CIPHER_DETAIL
    if (debug) {
        gslogMessagePrefix("DETAIL_RSACIPHER Data to encrypt - %d bytes: ",
                            (int)plaintextLen);
        gslogMessageHex((char *)plaintextNative, 0, (int)plaintextLen, 0, 0,
                        NULL);
    }
#endif

    // To get output length.
    outLen = ICC_EVP_PKEY_encrypt(ockCtx, keyCtx,
                              NULL, &outlen,
                              plaintextNative + (int) plaintextOff,  (size_t) plaintextLen);

    outLen = ICC_EVP_PKEY_encrypt(ockCtx, keyCtx,
                              ciphertextNative + (int) ciphertextOff, &outLen,
                              plaintextNative + (int) plaintextOff,  (size_t) plaintextLen);
    if (outLen == ICC_OSSL_FAILURE || outLen == ICC_FAILURE) {
#ifdef DEBUG_RSA_DETAIL
        if (debug) {
            gslogMessage(
                "DETAIL_RSACIPHER FAILURE ICC_EVP_PKEY_encrypt ");
        }
#endif
        throwOCKException(env, 0, "ICC_EVP_PKEY_encrypt failed");
        goto cleanup;
    }

#ifdef DEBUG_CIPHER_DETAIL
    if (debug) {
        gslogMessagePrefix("DETAIL_RSACIPHER Encrypted data - %d bytes: ",
                            outLen);
        gslogMessageHex((char *)ciphertextNative + (int)ciphertextOff, 0,
                        outLen, 0, 0, NULL);
    }
#endif


cleanup:
    if (plaintextNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, plaintext, plaintextNative, JNI_ABORT);
    }

    if (ciphertextNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, ciphertext, ciphertextNative, 0);
    }

    if (keyCtx != NULL) {
        ICC_EVP_PKEY_CTX_free(ockCtx, keyCtx);
    }

    if (debug) {
#ifdef DEBUG_CIPHER_DETAIL
        gslogMessage("DETAIL_RSACIPHER outLen %d", outLen);
#endif
        gslogFunctionExit(functionName);
    }

    return (jint) outLen;
}

/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    RSACIPHER_decrypt
 * Signature: (JJII[BII[BI)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_ock_NativeInterface_RSACIPHER_1decrypt(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong rsaKeyId,
    jint rsaPaddingId, jint mdId, jbyteArray ciphertext, jint ciphertextOff,
    jint ciphertextLen, jbyteArray plaintext, jint plaintextOff) {
    static const char *functionName = "NativeInterface.RSACIPHER_decrypt";

    ICC_CTX          *ockCtx            = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_EVP_PKEY     *ockRSA            = (ICC_EVP_PKEY *)((intptr_t)rsaKeyId);
    ICC_EVP_PKEY_CTX *keyCtx            = NULL;
    unsigned char    *plaintextNative   = NULL;
    unsigned char    *ciphertextNative  = NULL;
    size_t           *outLen;
    jboolean         isCopy;

    if (debug) {
        gslogFunctionEntry(functionName);
#ifdef DEBUG_RSA_DETAIL
        gslogMessage(
            "DETAIL_RSACIPHER rsaKeyId %lx rsaPaddingId %x mdId %x plaintextOff %d "
            "plaintextLen %d ciphertextOff %d",
            (long)rsaKeyId, rsaPaddingId, mdId, (int)plaintextOff, (int)plaintextLen,
            (int)ciphertextOff);
#endif
    }

    if ((ockRSA == NULL) || (plaintext == NULL) || (ciphertext == NULL) ||
        (plaintextOff < 0) || (plaintextOff > plaintextLen) ||
        (ciphertextOff < 0)) {
        throwOCKException(env, 0, "The RSA input parameters are incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return outLen;
    }

    keyCtx = ICC_EVP_PKEY_CTX_new(ockCtx, ockRSA, NULL);
    if (!keyCtx) {
        throwOCKException(env, 0, "Could not create RSA context.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return outLen;
    }

    int rc = ICC_EVP_PKEY_decrypt_init(ockCtx, keyCtx);
    if (rc != ICC_OSSL_SUCCESS) {
        throwOCKException(env, 0, "Could not initialize.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        goto cleanup;
    }


    if (-1 == setPadding(ockCtx, keyCtx, rsaPaddingId, mdId)) {
        throwOCKException(env, 0, "Could not set padding.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        goto cleanup;
    }

    plaintextNative  = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
        env, plaintext, &isCopy));
    ciphertextNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
        env, ciphertext, &isCopy));
    if (NULL == plaintextNative || NULL == ciphertextNative) {
#ifdef DEBUG_RSA_DETAIL
        if (debug) {
            gslogMessage(
                "DETAIL_RSACIPHER FAILURE plaintextNative or cihertextNative ");
        }
#endif
        throwOCKException(env, 0, "GetPrimitiveArrayCritical failed");

        goto cleanup;
    }
#ifdef DEBUG_CIPHER_DETAIL
    if (debug) {
        gslogMessagePrefix("DETAIL_RSACIPHER Data to encrypt - %d bytes: ",
                            (int)plaintextLen);
        gslogMessageHex((char *)plaintextNative, 0, (int)plaintextLen, 0, 0,
                        NULL);
    }
#endif

    // To get output length.
    outLen = ICC_EVP_PKEY_decrypt(ockCtx, keyCtx,
                              NULL, &outlen,
                              ciphertextNative + (int) ciphertextOff, (size_t) ciphertextLen);

    outLen = ICC_EVP_PKEY_decrypt(ockCtx, keyCtx,
                              plaintextNative + (int) plaintextOff,  &outLen,
                              ciphertextNative + (int) ciphertextOff, (size_t) ciphertextLen);
    if (outLen == ICC_OSSL_FAILURE || outLen == ICC_FAILURE) {
#ifdef DEBUG_RSA_DETAIL
        if (debug) {
            gslogMessage(
                "DETAIL_RSACIPHER FAILURE ICC_EVP_PKEY_decrypt ");
        }
#endif
        throwOCKException(env, 0, "ICC_EVP_PKEY_decrypt failed");
        goto cleanup;
    }

#ifdef DEBUG_CIPHER_DETAIL
    if (debug) {
        gslogMessagePrefix("DETAIL_RSACIPHER Encrypted data - %d bytes: ",
                            outLen);
        gslogMessageHex((char *)ciphertextNative + (int)ciphertextOff, 0,
                        outLen, 0, 0, NULL);
    }
#endif


cleanup:
    if (plaintextNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, plaintext, plaintextNative, 0);
    }

    if (ciphertextNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, ciphertext, ciphertextNative, JNI_ABORT);
    }

    if (keyCtx != NULL) {
        ICC_EVP_PKEY_CTX_free(ockCtx, keyCtx);
    }

    if (debug) {
#ifdef DEBUG_CIPHER_DETAIL
        gslogMessage("DETAIL_RSACIPHER outLen %d", outLen);
#endif
        gslogFunctionExit(functionName);
    }

    return outLen;
}

static int
rsaPaddingMap(int rsaPaddingId)
{
#ifdef DEBUG_RSA_DETAIL
    if (debug) {
        gslogMessage("DETAIL_RSACIPHER rsaPaddingId %lx ", (long)rsaPaddingId);
    }
#endif

    switch (rsaPaddingId) {
        case RSAPAD_NONE:
            return ICC_RSA_NO_PADDING;
        case RSAPAD_PKCS1:
            return ICC_RSA_PKCS1_PADDING;
        case RSAPAD_OAEP:
            return ICC_RSA_PKCS1_OAEP_PADDING;
        default:
            return -1;
    }
}

static char *
getDigestName(int mdId)
{
#ifdef DEBUG_RSA_DETAIL
    if (debug) {
        gslogMessage("DETAIL_RSACIPHER mdId %lx ", (long)mdId);
    }
#endif
    switch (mdId) {
        case SHA1:
            return "SHA1";
        case SHA224:
            return "SHA224";
        case SHA256:
            return "SHA256";
        case SHA512:
            return "SHA512";
        default:
            return NULL;
    }
}

static int
setPadding(ICC_CTX *icc_ctx, ICC_EVP_PKEY_CTX *ctx, int rsaPaddingId, int mdId)
{
    int rc = 0;
    int p1Pad = rsaPaddingMap(rsaPaddingId);
    const ICC_EVP_MD *md = NULL;

    if (p1Pad != ICC_RSA_NO_PADDING) {
        rc = ICC_EVP_PKEY_CTX_set_rsa_padding(icc_ctx, ctx, p1Pad);
        if (rc != ICC_OSSL_SUCCESS) {
            return -1;
        }
    }
    
    if (p1Pad == ICC_RSA_PKCS1_OAEP_PADDING) {
        md = ICC_EVP_get_digestbyname(icc_ctx, getDigestName(mdId));
        if (!md) {
            return -1;
        }

        rc = ICC_EVP_PKEY_CTX_set_rsa_oaep_md(icc_ctx, ctx, md);
        if (rc != ICC_OSSL_SUCCESS) {
            return -1;
        }

        rc = ICC_EVP_PKEY_CTX_set_rsa_mgf1_md(icc_ctx, ctx, md);
        if (rc != ICC_OSSL_SUCCESS) {
            return -1;
        }
    }

    return rc;
}
