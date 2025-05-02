/*
 * Copyright IBM Corp. 2023
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <openssl/evp.h>

#include "com_ibm_crypto_plus_provider_ossl_NativeOSSLImplementation.h"
#include "Digest.h"
#include <stdint.h>

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ossl_NativeOSSLImplementation
 * Method:    DIGEST_create
 * Signature: (Ljava/lang/String;)J
 */
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_ossl_NativeOSSLImplementation_DIGEST_1create(
    JNIEnv *env, jclass thisObj, jstring digestAlgo) {
    //static const char *functionName = "NativeOSSLImplementation.DIGEST_create";

    return -1;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ossl_NativeOSSLImplementation
 * Method:    DIGEST_copy
 * Signature: (J)J
 */
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_ossl_NativeOSSLImplementation_DIGEST_1copy(
    JNIEnv *env, jclass thisObj, jlong digestId) {
    //static const char *functionName = "NativeOSSLImplementation.DIGEST_copy";

    return -1;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ossl_NativeOSSLImplementation
 * Method:    DIGEST_update
 * Signature: (J[BII)V
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_ossl_NativeOSSLImplementation_DIGEST_1update(
    JNIEnv *env, jclass thisObj, jlong digestId,
    jbyteArray data, jint offset, jint dataLen) {
    //static const char *functionName = "NativeOSSLImplementation.DIGEST_update";

    return -1;
}

/*
 * Class:     com_ibm_crypto_plus_provider_ossl_NativeOSSLImplementation
 * Method:    DIGEST_updateFastJNI
 * Signature: (JJI)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_ossl_NativeOSSLImplementation_DIGEST_1updateFastJNI(
    JNIEnv *env, jclass thisObj, jlong digestId,
    jlong dataBuffer, jint dataLen) {
    //static const char *functionName = "NativeOSSLImplementation.DIGEST_updateFastJNI";

}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ossl_NativeOSSLImplementation
 * Method:    DIGEST_digest
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_ossl_NativeOSSLImplementation_DIGEST_1digest(
    JNIEnv *env, jclass thisObj, jlong digestId) {
    //static const char *functionName = "NativeOSSLImplementation.DIGEST_digest";

    return (jbyteArray)-1;
}

/*
 * Class:     com_ibm_crypto_plus_provider_ossl_NativeOSSLImplementation
 * Method:    DIGEST_digest_and_reset
 * Signature: (JJI)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_ossl_NativeOSSLImplementation_DIGEST_1digest_1and_1reset__JJI(
    JNIEnv *env, jclass thisObj, jlong digestId,
    jlong digestBytes, jint length) {
    //static const char *functionName = "NativeOSSLImplementation.DIGEST_digest_and_reset";

    
}

/*
 * Class:     com_ibm_crypto_plus_provider_ossl_NativeOSSLImplementation
 * Method:    DIGEST_digest_and_reset
 * Signature: (J[B)V
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_ossl_NativeOSSLImplementation_DIGEST_1digest_1and_1reset__J_3B(
    JNIEnv *env, jclass thisObj, jlong digestId,
    jbyteArray digestBytes) {
    //static const char *functionName = "NativeOSSLImplementation.DIGEST_digest_and_reset";

    return -1;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ossl_NativeOSSLImplementation
 * Method:    DIGEST_size
 * Signature: (J)V
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_ossl_NativeOSSLImplementation_DIGEST_1size(
    JNIEnv *env, jclass thisObj, jlong digestId) {
    //static const char *functionName = "NativeOSSLImplementation.DIGEST_size";

    return -1;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ossl_NativeOSSLImplementation
 * Method:    DIGEST_reset
 * Signature: (J)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_ossl_NativeOSSLImplementation_DIGEST_1reset(
    JNIEnv *env, jclass thisObj, jlong digestId) {
    //static const char *functionName = "NativeOSSLImplementation.DIGEST_reset";

}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ossl_NativeOSSLImplementation
 * Method:    DIGEST_delete
 * Signature: (J)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_ossl_NativeOSSLImplementation_DIGEST_1delete(
    JNIEnv *env, jclass thisObj, jlong digestId) {
    //static const char *functionName = "NativeOSSLImplementation.DIGEST_delete";

    
}
